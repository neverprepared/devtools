package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/neverprepared/devtools/internal/castore"
	"github.com/neverprepared/devtools/internal/check"
)

func newCACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "ca",
		Aliases: []string{"certs"},
		Short:   "Export TLS-inspection (DPI) CA certificates as a PEM bundle",
		Long: `Find the CA certificates a TLS-inspecting proxy installed on this machine and
write them to a PEM file that other tools can use.

Behind corporate TLS inspection the proxy's root lands in the macOS keychain,
where every tool carrying its own trust store (pip, npm, go, aws, git, cargo)
cannot see it. Those tools all want a PEM file instead. This produces one.

  devtools ca list              what inspection CAs are installed
  devtools ca detect            is this connection being inspected right now
  devtools ca export            write the bundle
  devtools ca env               the environment variables that use it`,
	}
	cmd.AddCommand(newCAListCmd(), newCADetectCmd(), newCAExportCmd(), newCAEnvCmd())
	return cmd
}

// scanOptions are the flags shared by the scanning subcommands.
type scanOptions struct {
	include     []string
	allNonApple bool
	keepExpired bool
	noLogin     bool
	noSystem    bool
	fromURL     string
	timeout     time.Duration
	extraFiles  []string
}

func (s *scanOptions) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringArrayVar(&s.include, "include", nil, "also treat subjects matching this regexp as inspection CAs (repeatable)")
	f.BoolVar(&s.allNonApple, "all-non-apple", false, "include every CA that is not in Apple's root store, not just recognised vendors")
	f.BoolVar(&s.keepExpired, "keep-expired", false, "keep expired certificates instead of dropping them")
	f.BoolVar(&s.noLogin, "no-login-keychain", false, "skip the login keychain")
	f.BoolVar(&s.noSystem, "no-system-keychain", false, "skip the system keychain")
	f.StringVar(&s.fromURL, "from-url", "", "also take the CA that signs this URL's connection (ground truth when inspection is active)")
	f.DurationVar(&s.timeout, "timeout", 10*time.Second, "handshake timeout for --from-url")
	f.StringArrayVar(&s.extraFiles, "from-file", nil, "also read certificates from this PEM file (repeatable)")
}

func (s *scanOptions) patterns() ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, p := range s.include {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("--include %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// scanResult is everything the scan found.
type scanResult struct {
	All      []castore.Cert
	Selected []castore.Cert
	AppleFPs map[string]bool
	Obs      *castore.Observation
}

// scan reads the configured sources and selects the inspection CAs.
func (s *scanOptions) scan(ctx context.Context) (*scanResult, error) {
	appleFPs, err := castore.AppleRootFingerprints(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading Apple's root store: %w", err)
	}

	var all []castore.Cert
	if !s.noLogin {
		path, err := castore.LoginKeychainPath()
		if err != nil {
			return nil, err
		}
		certs, err := castore.ReadKeychain(ctx, path, castore.SourceLogin)
		if err != nil {
			return nil, err
		}
		all = append(all, certs...)
	}
	if !s.noSystem {
		certs, err := castore.ReadKeychain(ctx, castore.SystemKeychain, castore.SourceSystem)
		if err != nil {
			return nil, err
		}
		all = append(all, certs...)
	}
	for _, path := range s.extraFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		all = append(all, castore.ParsePEM(data, castore.SourceFile)...)
	}
	all = castore.Dedup(all)

	res := &scanResult{All: all, AppleFPs: appleFPs}

	if s.fromURL != "" {
		obs, err := castore.ObserveChain(ctx, s.fromURL, s.timeout, all, appleFPs)
		if err != nil {
			return nil, err
		}
		res.Obs = obs
		if obs.Root != nil && obs.Inspecting {
			all = append(all, *obs.Root)
		}
	}

	pats, err := s.patterns()
	if err != nil {
		return nil, err
	}
	res.Selected = castore.Select(all, appleFPs, castore.SelectOptions{
		Include:        pats,
		AllNonAppleCAs: s.allNonApple,
		KeepExpired:    s.keepExpired,
	})
	castore.Sort(res.Selected)
	return res, nil
}

func newCAListCmd() *cobra.Command {
	var s scanOptions
	var showAll bool

	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List the TLS-inspection CAs installed on this machine",
		Long: `List the inspection CAs found in the keychains, and why each was flagged.

With --show-all, every certificate found is listed with its classification, so
you can spot an internal CA no vendor list would recognise and then select it
with --include.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			res, err := s.scan(c.Context())
			if err != nil {
				return err
			}

			w := c.OutOrStdout()
			listed := res.Selected
			if showAll {
				listed = res.All
				castore.Sort(listed)
			}

			if g.json {
				rep := check.NewReport("ca list", "keychains")
				rep.Set("certificates", listed)
				rep.Set("apple_root_count", len(res.AppleFPs))
				if len(res.Selected) == 0 {
					rep.Add(check.OK("inspection cas", "none found"))
				} else {
					rep.Add(check.Warnf("inspection cas", "%d found", len(res.Selected)))
				}
				return emitReport(c, rep)
			}

			if len(listed) == 0 {
				infof(w, "no TLS-inspection CAs found in the login or system keychain")
				infof(w, "if you are behind an inspecting proxy right now, try: devtools ca detect")
				return nil
			}

			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "COMMON NAME\tSOURCE\tCA\tEXPIRES\tVENDOR / REASON")
			for _, cert := range listed {
				reason := cert.Reason
				if reason == "" {
					reason = classification(cert)
				}
				expires := fmt.Sprintf("%s (%dd)", cert.NotAfter[:10], cert.DaysLeft)
				if cert.Expired() {
					expires = cert.NotAfter[:10] + " (EXPIRED)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\n",
					truncate(cert.CommonName, 44), cert.Source, cert.IsCA, expires, reason)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if !showAll {
				infof(w, "\n%d inspection CA(s). Export them with: devtools ca export", len(listed))
			}
			return nil
		},
	}
	s.register(cmd)
	cmd.Flags().BoolVar(&showAll, "show-all", false, "list every certificate found, not just the inspection CAs")
	return cmd
}

// classification describes a certificate that was not selected.
func classification(c castore.Cert) string {
	switch {
	case c.Vendor != "":
		return "vendor: " + c.Vendor
	case c.InAppleRoots:
		return "Apple-shipped public root"
	case !c.IsCA:
		return "not a CA"
	case c.SelfSigned:
		return "self-signed CA, not a recognised vendor"
	default:
		return "CA not in Apple's root store"
	}
}

func newCADetectCmd() *cobra.Command {
	var s scanOptions
	cmd := &cobra.Command{
		Use:   "detect [url]",
		Short: "Report whether this connection is being TLS-inspected, and by whom",
		Long: `Handshake with a URL and report which CA actually signed the connection.

Verification failing is not the test: an inspection proxy installs its root into
your keychain so that verification succeeds. So the chain is verified and the
root it anchored to is checked against Apple's shipped root store. A root that
is trusted locally but not shipped by Apple was installed here to sign traffic.

Defaults to https://example.com, which no proxy has a reason to exempt.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			target := "https://example.com"
			if len(args) == 1 {
				target = args[0]
			}
			s.fromURL = target

			res, err := s.scan(c.Context())
			if err != nil {
				return err
			}
			obs := res.Obs

			rep := check.NewReport("ca detect", target)
			rep.Set("observation", obs)

			if leaf := obs.Leaf(); leaf != nil {
				rep.Add(check.OK("leaf", "CN=%s, issued by %s",
					leaf.CommonName, castore.Cert(*leaf).Issuer))
			}
			switch {
			case !obs.Verified:
				rep.Add(check.Failf("chain", "did not verify against the local trust store: %s", obs.VerifyErr).
					Note("an inspecting proxy whose root is NOT installed looks exactly like this"))
			case obs.Inspecting:
				root := obs.Root
				detail := fmt.Sprintf("signed by a locally installed CA: %s", root.CommonName)
				res := check.Warnf("inspection", "%s", detail).
					Note("root source: %s", root.Source).
					Note("fingerprint: SHA256:%s", root.Fingerprint)
				if root.Vendor != "" {
					res = res.Note("vendor: %s", root.Vendor)
				}
				rep.Add(res)
				rep.Add(check.OK("next step", "devtools ca export --from-url %s", target))
			default:
				rep.Add(check.OK("inspection", "none: the chain anchors to an Apple-shipped root (%s)",
					obs.Root.CommonName))
			}
			return emitReport(c, rep)
		},
	}
	s.register(cmd)
	cmd.Flags().MarkHidden("from-url")
	return cmd
}

func newCAExportCmd() *cobra.Command {
	var (
		s          scanOptions
		out        string
		fullBundle bool
		noComments bool
		toStdout   bool
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the inspection CAs to a PEM file",
		Long: `Write the inspection CAs to a PEM bundle for reuse.

Two shapes of output, because the tools want different things:

  (default)       just the inspection CAs. This is what NODE_EXTRA_CA_CERTS
                  wants, since Node ADDS these to its built-in store.
  --full-bundle   the inspection CAs plus every Apple-shipped root. This is
                  what SSL_CERT_FILE, REQUESTS_CA_BUNDLE, AWS_CA_BUNDLE and
                  friends want, since they REPLACE the trust store and would
                  otherwise reject every public site.

Export both and you can set all of them correctly; "devtools ca env" prints the
lines to do it.

Examples:
  devtools ca export
  devtools ca export --full-bundle
  devtools ca export --from-url https://example.com
  devtools ca export --include 'Example Corp Internal Root'
  devtools ca export --stdout | openssl crl2pkcs7 -nocrl -certfile /dev/stdin | openssl pkcs7 -print_certs -noout`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			res, err := s.scan(c.Context())
			if err != nil {
				return err
			}
			if len(res.Selected) == 0 {
				return fmt.Errorf("no inspection CAs found; run 'devtools ca list --show-all' to see what is installed, then select one with --include")
			}

			bundle := res.Selected
			if fullBundle {
				appleRoots, err := castore.ReadKeychain(c.Context(), castore.AppleRoots, castore.SourceApple)
				if err != nil {
					return err
				}
				bundle = castore.Dedup(append(append([]castore.Cert{}, res.Selected...), appleRoots...))
			}
			data := castore.WritePEM(bundle, !noComments)

			w := c.OutOrStdout()
			if toStdout {
				_, err := w.Write(data)
				return err
			}

			if out == "" {
				dir, err := castore.DefaultDir()
				if err != nil {
					return err
				}
				name := "mitm-ca.pem"
				if fullBundle {
					name = "ca-bundle.pem"
				}
				out = filepath.Join(dir, name)
			}

			if g.dryRun {
				infof(w, "dry-run: would write %d certificate(s) to %s:", len(bundle), out)
				for _, cert := range res.Selected {
					infof(w, "  %s (%s)", cert.CommonName, cert.Reason)
				}
				return nil
			}

			if err := castore.WriteFile(out, data); err != nil {
				return err
			}
			n, err := castore.VerifyBundle(out)
			if err != nil {
				return fmt.Errorf("wrote %s but it did not verify: %w", out, err)
			}

			infof(w, "wrote %s (%d certificate(s), %d bytes)", out, n, len(data))
			for _, cert := range res.Selected {
				infof(w, "  %s - %s", cert.CommonName, cert.Reason)
			}
			if !fullBundle {
				infof(w, "\nThis file holds only the inspection CAs, which is what NODE_EXTRA_CA_CERTS wants.")
				infof(w, "For SSL_CERT_FILE and friends, which replace the trust store, also run:")
				infof(w, "  devtools ca export --full-bundle")
			}
			infof(w, "\nSet the environment variables with: devtools ca env")
			return nil
		},
	}
	s.register(cmd)
	f := cmd.Flags()
	f.StringVarP(&out, "out", "o", "", "output path (default ~/.config/devtools/ca/mitm-ca.pem, or ca-bundle.pem with --full-bundle)")
	f.BoolVar(&fullBundle, "full-bundle", false, "append every Apple-shipped root, producing a complete replacement trust store")
	f.BoolVar(&noComments, "no-comments", false, "omit the human-readable header above each certificate")
	f.BoolVar(&toStdout, "stdout", false, "write to stdout instead of a file")
	return cmd
}

// envVars are the variables that point a tool at a CA bundle. Replaces is the
// distinction that matters: a variable that REPLACES the trust store needs the
// full bundle, or every public site stops verifying.
var envVars = []struct {
	Name     string
	Tool     string
	Replaces bool
}{
	{"SSL_CERT_FILE", "OpenSSL, Go, many others", true},
	{"REQUESTS_CA_BUNDLE", "Python requests", true},
	{"CURL_CA_BUNDLE", "curl", true},
	{"AWS_CA_BUNDLE", "AWS CLI and SDKs", true},
	{"GIT_SSL_CAINFO", "git", true},
	{"PIP_CERT", "pip", true},
	{"CARGO_HTTP_CAINFO", "cargo", true},
	{"HTTPLIB2_CA_CERTS", "httplib2", true},
	{"NODE_EXTRA_CA_CERTS", "Node.js (adds to its built-in store)", false},
}

func newCAEnvCmd() *cobra.Command {
	var bundle, mitm string
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Print the environment variables that point tools at the bundle",
		Long: `Print shell exports pointing the usual suspects at the exported bundles.

Each variable gets the right file. The ones that REPLACE a tool's trust store
get the full bundle; NODE_EXTRA_CA_CERTS gets the inspection-CA file, because
Node adds it to its built-in store and handing it a full bundle is both
redundant and slow.

  eval "$(devtools ca env)"                      this shell only
  devtools ca env >> ~/.config/shell/env.sh      permanently`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			dir, err := castore.DefaultDir()
			if err != nil {
				return err
			}
			if bundle == "" {
				bundle = filepath.Join(dir, "ca-bundle.pem")
			}
			if mitm == "" {
				mitm = filepath.Join(dir, "mitm-ca.pem")
			}

			w := c.OutOrStdout()
			var missing []string
			for _, path := range []string{bundle, mitm} {
				if _, err := os.Stat(path); err != nil {
					missing = append(missing, path)
				}
			}
			for _, m := range missing {
				fmt.Fprintf(w, "# missing: %s (run: devtools ca export%s)\n",
					m, map[bool]string{true: " --full-bundle"}[m == bundle])
			}

			for _, v := range envVars {
				path := mitm
				if v.Replaces {
					path = bundle
				}
				fmt.Fprintf(w, "export %s=%q  # %s\n", v.Name, path, v.Tool)
			}
			fmt.Fprintf(w, "\n# Java needs a keystore, not a PEM:\n")
			fmt.Fprintf(w, "#   keytool -importcert -trustcacerts -alias inspection-ca -file %q \\\n", mitm)
			fmt.Fprintf(w, "#     -keystore \"$JAVA_HOME/lib/security/cacerts\" -storepass changeit\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&bundle, "bundle", "", "path to the full bundle (default ~/.config/devtools/ca/ca-bundle.pem)")
	cmd.Flags().StringVar(&mitm, "mitm", "", "path to the inspection-CA-only file (default ~/.config/devtools/ca/mitm-ca.pem)")
	return cmd
}

// truncate shortens a string for table output.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
