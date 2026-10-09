package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/neverprepared/devtools/internal/msgraph"
	"github.com/neverprepared/devtools/internal/teams"
)

// Transports devtools can set presence through.
const (
	viaGraph       = "graph"
	viaAppleScript = "applescript"
)

// teamsRun is the flag state shared by every teams subcommand.
type teamsRun struct {
	opts      teams.Options
	noRestore bool
	via       string
	clientID  string
	tenant    string
}

func newTeamsCmd() *cobra.Command {
	r := &teamsRun{opts: teams.DefaultOptions(), via: viaGraph}

	cmd := &cobra.Command{
		Use:   "teams",
		Short: "Set Microsoft Teams presence",
		Long: `Set Microsoft Teams presence from the command line.

Two transports, selected with --via:

  graph        Microsoft Graph setUserPreferredPresence. The default. Needs a
               one-time "devtools teams auth login", then no Accessibility
               permission, no focus stealing, and --revert-after is enforced by
               Graph instead of blocking this process. Teams must still be
               signed in somewhere: Graph only applies a preferred presence
               while a presence session exists, and reports Offline otherwise.

  applescript  Types the matching slash command into the Teams command box
               (Cmd+E). Needs no login, but does need Accessibility permission
               for whichever app runs devtools: System Settings > Privacy &
               Security > Accessibility, and it briefly takes focus.

Run "devtools doctor" to see which transports are ready.`,
	}

	f := cmd.PersistentFlags()
	f.StringVar(&r.via, "via", r.via, `transport: "graph" or "applescript"`)
	f.StringVar(&r.clientID, "client-id", "", "Entra application (client) id for Graph auth (default: the Azure CLI public client)")
	f.StringVar(&r.tenant, "tenant", "", `Entra tenant id for Graph auth (default: "organizations")`)
	f.StringVar(&r.opts.App, "app", r.opts.App, `applescript: Teams application name (use "Microsoft Teams classic" for the old client)`)
	f.DurationVar(&r.opts.ActivateDelay, "activate-delay", r.opts.ActivateDelay, "applescript: wait after activating Teams before typing")
	f.DurationVar(&r.opts.KeyDelay, "key-delay", r.opts.KeyDelay, "applescript: wait between keystrokes")
	f.BoolVar(&r.noRestore, "no-restore", false, "applescript: leave Teams in front instead of returning focus")

	// One subcommand per presence state, so `devtools teams away` just works.
	for _, st := range teams.Statuses {
		st := st
		cmd.AddCommand(&cobra.Command{
			Use:     st.Name,
			Short:   st.Summary,
			Args:    cobra.NoArgs,
			Aliases: st.Aliases,
			RunE: func(c *cobra.Command, _ []string) error {
				return r.set(c, st, 0)
			},
		})
	}

	cmd.AddCommand(newTeamsSetCmd(r), newTeamsClearCmd(r), newTeamsStatusesCmd(), newTeamsAuthCmd(r))
	return cmd
}

func newTeamsSetCmd(r *teamsRun) *cobra.Command {
	var revertAfter time.Duration
	var revertTo string

	cmd := &cobra.Command{
		Use:   "set <status>",
		Short: "Set presence by name or alias",
		Long: `Set presence by name or alias, e.g. "devtools teams set dnd".

--revert-after behaves differently per transport, because Graph can do it
properly and AppleScript cannot:

  graph        becomes Graph's expirationDuration. This process exits
               immediately and Graph drops the preferred presence when the
               timer elapses, handing presence back to whatever Teams
               calculates. Nothing has to stay running.

  applescript  devtools stays in the foreground for the duration and then sets
               --revert-to (default available). Kill the process and the
               presence stays put.

Graph expiry always reverts to calculated presence, so --revert-to cannot be
honoured there; pass --via applescript if you need to revert to a specific
status.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			st, err := teams.Resolve(args[0])
			if err != nil {
				return err
			}

			if r.via == viaGraph {
				if c.Flags().Changed("revert-to") {
					return errors.New(
						"--revert-to is not supported with --via graph: Graph expiry always reverts to " +
							"calculated presence, not to a chosen status\nuse --via applescript for a targeted revert")
				}
				// Hand the hold to Graph and exit; nothing blocks.
				return r.set(c, st, revertAfter)
			}

			if err := r.set(c, st, 0); err != nil {
				return err
			}
			if revertAfter <= 0 {
				return nil
			}
			back, err := teams.Resolve(revertTo)
			if err != nil {
				return fmt.Errorf("--revert-to: %w", err)
			}
			if g.dryRun {
				infof(c.OutOrStdout(), "dry-run: would wait %s then set presence to %s", revertAfter, back.Name)
				return nil
			}
			infof(c.OutOrStdout(), "waiting %s before reverting to %s (Ctrl-C to stay %s)", revertAfter, back.Name, st.Name)
			select {
			case <-c.Context().Done():
				return c.Context().Err()
			case <-time.After(revertAfter):
			}
			return r.set(c, back, 0)
		},
	}
	cmd.Flags().DurationVar(&revertAfter, "revert-after", 0, "how long to hold this presence before it reverts")
	cmd.Flags().StringVar(&revertTo, "revert-to", "available", "status to revert to (--via applescript only)")
	return cmd
}

func newTeamsClearCmd(r *teamsRun) *cobra.Command {
	return &cobra.Command{
		Use:   "clear",
		Short: "Clear the preferred presence, handing presence back to Teams",
		Long: `Remove the preferred presence so Teams goes back to calculating it from
your activity, meetings and calendar.

Graph only. Setting "available" is not the same thing: that pins presence to
Available, where clearing lets Teams decide again. The Teams command box has
no equivalent, so there is no AppleScript implementation.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if r.via != viaGraph {
				return fmt.Errorf("clear requires --via graph: the Teams command box can only set a status, never un-set one")
			}
			if g.dryRun {
				path, err := graphUserPathForDryRun("presence/clearUserPreferredPresence")
				if err != nil {
					return err
				}
				infof(c.OutOrStdout(), "dry-run: would clear preferred presence:\nPOST %s", path)
				return nil
			}
			client, err := r.graphClient()
			if err != nil {
				return err
			}
			if err := teams.ClearViaGraph(c.Context(), client); err != nil {
				return err
			}
			infof(c.OutOrStdout(), "Teams preferred presence cleared; presence is calculated again")
			return nil
		},
	}
}

func newTeamsStatusesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "statuses",
		Aliases: []string{"list"},
		Short:   "List the presence states devtools can set",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			w := c.OutOrStdout()
			fmt.Fprintf(w, "%-10s %-12s %-16s %s\n", "NAME", "SLASH", "GRAPH", "SUMMARY")
			for _, st := range teams.Statuses {
				graph := st.Availability
				if st.Activity != st.Availability {
					graph = st.Availability + "/" + st.Activity
				}
				fmt.Fprintf(w, "%-10s %-12s %-16s %s\n", st.Name, st.Command, graph, st.Summary)
			}
			return nil
		},
	}
}

// set dispatches one presence change to the selected transport.
func (r *teamsRun) set(c *cobra.Command, st teams.Status, hold time.Duration) error {
	switch r.via {
	case viaGraph:
		return r.setViaGraph(c, st, hold)
	case viaAppleScript:
		r.opts.Restore = !r.noRestore
		return r.setViaAppleScript(c, st)
	default:
		return fmt.Errorf("unknown --via %q: want %q or %q", r.via, viaGraph, viaAppleScript)
	}
}

func (r *teamsRun) setViaGraph(c *cobra.Command, st teams.Status, hold time.Duration) error {
	body := teams.GraphBody(st, hold)

	if g.dryRun {
		path, err := graphUserPathForDryRun("presence/setUserPreferredPresence")
		if err != nil {
			return err
		}
		pretty, err := json.MarshalIndent(body, "", "  ")
		if err != nil {
			return err
		}
		w := c.OutOrStdout()
		infof(w, "dry-run: would set Teams presence to %s via Graph:", st.Name)
		fmt.Fprintf(w, "POST %s\nContent-Type: application/json\n\n%s\n", path, pretty)
		return nil
	}

	client, err := r.graphClient()
	if err != nil {
		return err
	}
	if err := teams.SetViaGraph(c.Context(), client, st, hold); err != nil {
		return err
	}
	if body.ExpirationDuration != "" {
		infof(c.OutOrStdout(), "Teams presence -> %s (expires in %s, then Teams calculates it again)",
			st.Name, body.ExpirationDuration)
		return nil
	}
	infof(c.OutOrStdout(), "Teams presence -> %s", st.Name)
	return nil
}

func (r *teamsRun) setViaAppleScript(c *cobra.Command, st teams.Status) error {
	if g.dryRun {
		w := c.OutOrStdout()
		infof(w, "dry-run: would set Teams presence to %s via %s; AppleScript:", st.Name, st.Command)
		fmt.Fprint(w, teams.Script(st, r.opts, ""))
		return nil
	}
	if err := teams.Set(c.Context(), st, r.opts); err != nil {
		return err
	}
	infof(c.OutOrStdout(), "Teams presence -> %s", st.Name)
	return nil
}

// graphClient loads the stored token, turning the "never logged in" case into
// an instruction rather than a bare error. Graph is the default transport, so
// this is the message a first-time user sees.
func (r *teamsRun) graphClient() (*msgraph.Client, error) {
	path, err := msgraph.TokenPath()
	if err != nil {
		return nil, err
	}
	client, err := msgraph.NewClient(path)
	if errors.Is(err, msgraph.ErrNoToken) {
		return nil, fmt.Errorf("not signed in to Microsoft Graph\n" +
			"  run:  devtools teams auth login\n" +
			"  or:   devtools teams <status> --via applescript   (no login, needs Accessibility permission)")
	}
	if err != nil {
		return nil, err
	}
	if !client.Token.HasScope(msgraph.PresenceScope) {
		return nil, fmt.Errorf("the stored token does not carry %s\n"+
			"Azure will not add a scope to an existing grant, so sign in again to consent to it:\n"+
			"  devtools teams auth logout && devtools teams auth login", msgraph.PresenceScope)
	}
	return client, nil
}

// graphUserPathForDryRun renders the request path for --dry-run. It uses the
// stored user id when there is one and a placeholder otherwise, so --dry-run
// works before you have ever logged in.
func graphUserPathForDryRun(suffix string) (string, error) {
	path, err := msgraph.TokenPath()
	if err != nil {
		return "", err
	}
	if t, err := msgraph.LoadToken(path); err == nil && t.UserID != "" {
		return "/users/" + t.UserID + "/" + suffix, nil
	}
	return "/users/{your-user-id}/" + suffix, nil
}

func newTeamsAuthCmd(r *teamsRun) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage the Microsoft Graph login used by --via graph",
	}
	cmd.AddCommand(newTeamsAuthLoginCmd(r), newTeamsAuthStatusCmd(), newTeamsAuthLogoutCmd())
	return cmd
}

func newTeamsAuthLoginCmd(r *teamsRun) *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Sign in to Microsoft Graph with a device code",
		Long: `Start a device-code login and store the resulting token.

devtools prints a URL and a code; you open the URL, enter the code, and consent
to Presence.ReadWrite. The token is written to ~/.config/devtools/msgraph as a
mode-0600 file, and refreshes itself from then on.

Presence.ReadWrite must be consented HERE, at login. Azure refuses to add a
scope to an existing grant, so a token captured without it can never be
upgraded - it has to be replaced.

By default this authenticates as the Azure CLI public client, which needs no
app registration because it is already consented in most tenants. That also
means devtools presents itself to your tenant as the Azure CLI. Register your
own Entra app with delegated Presence.ReadWrite and pass --client-id to avoid
that.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			w := c.OutOrStdout()
			scopes := []string{msgraph.PresenceScope}

			if g.dryRun {
				id := r.clientID
				if id == "" {
					id = msgraph.DefaultClientID + " (Azure CLI public client)"
				}
				tenant := r.tenant
				if tenant == "" {
					tenant = "organizations"
				}
				infof(w, "dry-run: would start a device-code login\n  client-id: %s\n  tenant:    %s\n  scopes:    %s offline_access",
					id, tenant, msgraph.PresenceScope)
				return nil
			}

			dc, err := msgraph.StartDeviceCode(c.Context(), r.clientID, r.tenant, scopes)
			if err != nil {
				return fmt.Errorf("starting device-code login: %w", err)
			}

			// Azure's own message already names the URL and code; prefer it,
			// since it is localised and stays correct if the URL changes.
			if dc.Message != "" {
				infof(w, "%s", dc.Message)
			} else {
				infof(w, "open %s and enter the code %s", dc.VerificationURI, dc.UserCode)
			}
			infof(w, "waiting for you to finish signing in...")

			tok, err := msgraph.PollDeviceCode(c.Context(), r.clientID, r.tenant, dc)
			if err != nil {
				return fmt.Errorf("completing device-code login: %w", err)
			}
			if !tok.HasScope(msgraph.PresenceScope) {
				return fmt.Errorf("sign-in succeeded but the token does not carry %s\n"+
					"the tenant may have withheld consent; nothing was stored", msgraph.PresenceScope)
			}

			path, err := msgraph.TokenPath()
			if err != nil {
				return err
			}
			if err := msgraph.SaveToken(path, tok); err != nil {
				return err
			}
			who := tok.Account
			if who == "" {
				who = "signed in"
			}
			infof(w, "stored token for %s in %s", who, path)
			return nil
		},
	}
}

func newTeamsAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether a Graph token is stored and usable",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			w := c.OutOrStdout()
			path, err := msgraph.TokenPath()
			if err != nil {
				return err
			}
			t, err := msgraph.LoadToken(path)
			if errors.Is(err, msgraph.ErrNoToken) {
				infof(w, "not signed in (no token at %s)", path)
				infof(w, "run: devtools teams auth login")
				return &ExitError{Code: 2}
			}
			if err != nil {
				return err
			}
			reportToken(w, path, t)
			if !t.HasScope(msgraph.PresenceScope) {
				return &ExitError{Code: 2}
			}
			return nil
		},
	}
}

// reportToken prints the token's state. It deliberately prints no part of the
// token itself, only the claims needed to tell whether it will work.
func reportToken(w io.Writer, path string, t *msgraph.Token) {
	infof(w, "signed in as %s", t.Account)
	infof(w, "  token:     %s", path)
	infof(w, "  tenant:    %s", t.TenantID)
	infof(w, "  client-id: %s", t.ClientID)

	switch {
	case t.AccessToken == "":
		infof(w, "  access:    none stored")
	case time.Until(t.Expiry) <= 0:
		infof(w, "  access:    expired %s ago (refreshes on next use)", time.Since(t.Expiry).Round(time.Second))
	default:
		infof(w, "  access:    valid for %s", time.Until(t.Expiry).Round(time.Second))
	}

	if t.RefreshToken == "" {
		infof(w, "  refresh:   NONE - presence will stop working when the access token expires")
	}
	if t.HasScope(msgraph.PresenceScope) {
		infof(w, "  scopes:    %s present", msgraph.PresenceScope)
		return
	}
	infof(w, "  scopes:    %s MISSING - sign in again to consent to it", msgraph.PresenceScope)
}

func newTeamsAuthLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete the stored Graph token",
		Long: `Delete the locally stored token.

This does not revoke the grant in Entra; it only removes this machine's copy.
Revoke the application's access from your account's security settings if you
want it gone server-side.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			path, err := msgraph.TokenPath()
			if err != nil {
				return err
			}
			if g.dryRun {
				infof(c.OutOrStdout(), "dry-run: would delete %s", path)
				return nil
			}
			if err := msgraph.DeleteToken(path); err != nil {
				return err
			}
			infof(c.OutOrStdout(), "deleted %s", path)
			return nil
		},
	}
}
