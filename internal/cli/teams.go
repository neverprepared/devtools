package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/neverprepared/devtools/internal/teams"
)

func newTeamsCmd() *cobra.Command {
	opts := teams.DefaultOptions()
	var noRestore bool

	cmd := &cobra.Command{
		Use:   "teams",
		Short: "Drive the Microsoft Teams desktop client",
		Long: `Set Microsoft Teams presence from the command line.

Teams exposes no local API for presence, so devtools types the matching slash
command into the Teams command box (Cmd+E) with AppleScript. That needs
Accessibility permission for your terminal: System Settings > Privacy &
Security > Accessibility. Run "devtools doctor" to check.`,
	}

	cmd.PersistentFlags().StringVar(&opts.App, "app", opts.App, `Teams application name (use "Microsoft Teams classic" for the old client)`)
	cmd.PersistentFlags().DurationVar(&opts.ActivateDelay, "activate-delay", opts.ActivateDelay, "wait after activating Teams before typing (raise this if presence changes miss)")
	cmd.PersistentFlags().DurationVar(&opts.KeyDelay, "key-delay", opts.KeyDelay, "wait between keystrokes")
	cmd.PersistentFlags().BoolVar(&noRestore, "no-restore", false, "leave Teams in front instead of returning focus to the previous app")

	// One subcommand per presence state, so `devtools teams away` just works.
	for _, st := range teams.Statuses {
		st := st
		sub := &cobra.Command{
			Use:     st.Name,
			Short:   st.Summary,
			Args:    cobra.NoArgs,
			Aliases: st.Aliases,
			RunE: func(c *cobra.Command, _ []string) error {
				opts.Restore = !noRestore
				return runTeamsSet(c, st, opts)
			},
		}
		cmd.AddCommand(sub)
	}

	cmd.AddCommand(newTeamsSetCmd(&opts, &noRestore))
	cmd.AddCommand(newTeamsStatusesCmd())
	return cmd
}

func newTeamsSetCmd(opts *teams.Options, noRestore *bool) *cobra.Command {
	var revertAfter time.Duration
	var revertTo string

	cmd := &cobra.Command{
		Use:   "set <status>",
		Short: "Set presence by name or alias",
		Long: `Set presence by name or alias, e.g. "devtools teams set dnd".

With --revert-after, devtools stays in the foreground for the given duration and
then switches presence back (to --revert-to, default available). Useful as the
body of a launchd agent or a shell alias: devtools teams set dnd --revert-after 45m`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			st, err := teams.Resolve(args[0])
			if err != nil {
				return err
			}
			opts.Restore = !*noRestore
			if err := runTeamsSet(c, st, *opts); err != nil {
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
			return runTeamsSet(c, back, *opts)
		},
	}
	cmd.Flags().DurationVar(&revertAfter, "revert-after", 0, "after this long, switch presence back (blocks until then)")
	cmd.Flags().StringVar(&revertTo, "revert-to", "available", "status to revert to with --revert-after")
	return cmd
}

func newTeamsStatusesCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "statuses",
		Aliases: []string{"list"},
		Short:   "List the presence states devtools can set",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			w := c.OutOrStdout()
			for _, st := range teams.Statuses {
				fmt.Fprintf(w, "%-10s %-12s %s\n", st.Name, st.Command, st.Summary)
			}
			return nil
		},
	}
}

func runTeamsSet(c *cobra.Command, st teams.Status, opts teams.Options) error {
	if g.dryRun {
		w := c.OutOrStdout()
		infof(w, "dry-run: would set Teams presence to %s via %s; AppleScript:", st.Name, st.Command)
		fmt.Fprint(w, teams.Script(st, opts, ""))
		return nil
	}
	if err := teams.Set(c.Context(), st, opts); err != nil {
		return err
	}
	infof(c.OutOrStdout(), "Teams presence -> %s", st.Name)
	return nil
}
