package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/neverprepared/devtools/internal/crontab"
)

func newCronCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cron",
		Short: "Manage devtools-owned crontab entries",
		Long: `Add, list and remove crontab entries that devtools owns.

Managed lines carry a trailing "` + crontab.Marker + `<name>" marker; devtools never
rewrites or removes a line without one, so hand-written entries are safe.

On macOS, cron requires Full Disk Access for /usr/sbin/cron and does not run
while the machine is asleep. For anything user-facing, prefer
"devtools launchd install" instead.`,
	}
	cmd.AddCommand(newCronAddCmd(), newCronListCmd(), newCronRemoveCmd(), newCronEditCmd())
	return cmd
}

func newCronAddCmd() *cobra.Command {
	var name, schedule string
	cmd := &cobra.Command{
		Use:     "add --name <name> --schedule <cron> -- <command> [args...]",
		Aliases: []string{"set", "upsert"},
		Short:   "Add or replace a managed crontab entry",
		Long: `Add or replace a managed crontab entry. Re-running with the same --name
replaces that entry in place, so this is safe to run repeatedly.

Example:
  devtools cron add --name teams-away --schedule "30 17 * * 1-5" -- \
      /usr/local/bin/devtools teams away`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := crontab.ValidateName(name); err != nil {
				return err
			}
			if err := crontab.ValidateSchedule(schedule); err != nil {
				return err
			}
			command := strings.Join(args, " ")
			current, err := crontab.Read(c.Context())
			if err != nil {
				return err
			}
			updated := crontab.Upsert(current, name, schedule, command)

			w := c.OutOrStdout()
			if g.dryRun {
				infof(w, "dry-run: would install this line:")
				fmt.Fprintln(w, "  "+crontab.Render(name, schedule, command))
				return nil
			}
			if err := crontab.Write(c.Context(), updated); err != nil {
				return err
			}
			infof(w, "installed cron entry %q: %s %s", name, schedule, command)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "managed entry name (used as the ownership marker)")
	cmd.Flags().StringVar(&schedule, "schedule", "", `cron schedule, e.g. "*/5 * * * *" or "@hourly"`)
	return cmd
}

func newCronListCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List managed crontab entries",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			w := c.OutOrStdout()
			if all {
				content, err := crontab.Read(c.Context())
				if err != nil {
					return err
				}
				if strings.TrimSpace(content) == "" {
					infof(w, "crontab is empty")
					return nil
				}
				fmt.Fprint(w, content)
				return nil
			}
			entries, err := crontab.List(c.Context())
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				infof(w, "no devtools-managed cron entries")
				return nil
			}
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSCHEDULE\tCOMMAND")
			for _, e := range entries {
				fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Name, e.Schedule, e.Command)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "print the whole crontab, managed or not")
	return cmd
}

func newCronRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "remove <name>",
		Aliases: []string{"rm", "delete"},
		Short:   "Remove a managed crontab entry",
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			current, err := crontab.Read(c.Context())
			if err != nil {
				return err
			}
			updated, found := crontab.Remove(current, name)
			if !found {
				return fmt.Errorf("no devtools-managed cron entry named %q", name)
			}
			w := c.OutOrStdout()
			if g.dryRun {
				infof(w, "dry-run: would remove cron entry %q", name)
				return nil
			}
			if err := crontab.Write(c.Context(), updated); err != nil {
				return err
			}
			infof(w, "removed cron entry %q", name)
			return nil
		},
	}
}

func newCronEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Open the crontab in $EDITOR (plain crontab -e)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return runInteractive(c, "crontab", "-e")
		},
	}
}
