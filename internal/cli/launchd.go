package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/neverprepared/devtools/internal/launchd"
)

func newLaunchdCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "launchd",
		Aliases: []string{"agent"},
		Short:   "Manage per-user LaunchAgents",
		Long: `Create and manage LaunchAgents in ~/Library/LaunchAgents.

devtools only ever touches agents whose label starts with "` + launchd.LabelPrefix + `",
so your own agents and anything an installer created are left alone.`,
	}
	cmd.AddCommand(
		newLaunchdInstallCmd(),
		newLaunchdUninstallCmd(),
		newLaunchdListCmd(),
		newLaunchdStatusCmd(),
		newLaunchdRunCmd(),
		newLaunchdLogsCmd(),
		newLaunchdCatCmd(),
	)
	return cmd
}

func newLaunchdInstallCmd() *cobra.Command {
	var (
		name      string
		interval  time.Duration
		at        []string
		workdir   string
		env       []string
		runAtLoad bool
		keepAlive bool
		stdout    string
		stderr    string
		nice      int
		noLoad    bool
	)

	cmd := &cobra.Command{
		Use:   "install --name <name> (--interval <dur> | --at <spec>) -- <command> [args...]",
		Short: "Write and load a LaunchAgent",
		Long: `Write a LaunchAgent plist and load it into your GUI session.

Schedules:
  --interval 15m            run every 15 minutes
  --at 09:00                run daily at 09:00
  --at Mon-Fri@08:45        run on weekdays at 08:45
  --at 'weekdays@17:30'     same, using the weekdays alias
  --at '*@*:15'             run every hour at quarter past
  (--at may be repeated; each spec adds StartCalendarInterval entries)

Examples:
  devtools launchd install --name teams-busy --at Mon-Fri@09:00 -- \
      /usr/local/bin/devtools teams busy
  devtools launchd install --name teams-away --at Mon-Fri@17:30 -- \
      /usr/local/bin/devtools teams away

launchd execs the program directly with no shell and almost no environment, so
give an absolute path (devtools resolves a bare name via PATH for you) and pass
any variables the command needs with --env.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			if c.ArgsLenAtDash() > 0 {
				return fmt.Errorf("put only the command after --, got extra arguments before it")
			}

			agent := &launchd.Agent{
				Label:            launchd.QualifyLabel(name),
				Program:          args,
				WorkingDirectory: workdir,
				StartInterval:    interval,
				RunAtLoad:        runAtLoad,
				KeepAlive:        keepAlive,
				StdoutPath:       stdout,
				StderrPath:       stderr,
			}
			if c.Flags().Changed("nice") {
				agent.Nice = &nice
			}

			var err error
			if agent.Env, err = parseEnv(env); err != nil {
				return err
			}
			for _, spec := range at {
				entries, err := launchd.ParseAt(spec)
				if err != nil {
					return err
				}
				agent.Calendar = append(agent.Calendar, entries...)
			}
			if err := agent.Validate(); err != nil {
				return err
			}

			w := c.OutOrStdout()
			if g.dryRun {
				path, _ := launchd.PlistPath(agent.Label)
				infof(w, "dry-run: would write %s:", path)
				fmt.Fprint(w, agent.Plist())
				return nil
			}
			if err := agent.ApplyDefaultLogs(); err != nil {
				return err
			}
			path, err := agent.Write()
			if err != nil {
				return err
			}
			infof(w, "wrote %s", path)
			if noLoad {
				infof(w, "not loaded (--no-load); load it with: devtools launchd install ... or launchctl bootstrap")
				return nil
			}
			if err := launchd.Bootstrap(c.Context(), agent.Label, path); err != nil {
				return err
			}
			infof(w, "loaded %s", agent.Label)
			infof(w, "logs: %s", agent.StdoutPath)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&name, "name", "", `agent name; the label becomes `+launchd.LabelPrefix+`<name>`)
	f.DurationVar(&interval, "interval", 0, "run every interval (StartInterval), e.g. 15m")
	f.StringArrayVar(&at, "at", nil, "calendar schedule, e.g. 09:00 or Mon-Fri@08:45 (repeatable)")
	f.StringVar(&workdir, "workdir", "", "working directory for the command")
	f.StringArrayVar(&env, "env", nil, "environment variable as KEY=VALUE (repeatable)")
	f.BoolVar(&runAtLoad, "run-at-load", false, "also run once immediately when loaded or at login")
	f.BoolVar(&keepAlive, "keep-alive", false, "restart the command whenever it exits (long-running daemons)")
	f.StringVar(&stdout, "stdout", "", "stdout log path (default ~/Library/Logs/devtools/<label>.out.log)")
	f.StringVar(&stderr, "stderr", "", "stderr log path (default ~/Library/Logs/devtools/<label>.err.log)")
	f.IntVar(&nice, "nice", 0, "process nice value")
	f.BoolVar(&noLoad, "no-load", false, "write the plist but do not load it")
	return cmd
}

func newLaunchdUninstallCmd() *cobra.Command {
	var keepPlist bool
	cmd := &cobra.Command{
		Use:     "uninstall <name>",
		Aliases: []string{"remove", "rm"},
		Short:   "Unload a LaunchAgent and delete its plist",
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			label := launchd.QualifyLabel(args[0])
			path, err := launchd.PlistPath(label)
			if err != nil {
				return err
			}
			w := c.OutOrStdout()
			if g.dryRun {
				infof(w, "dry-run: would unload %s and remove %s", label, path)
				return nil
			}
			if err := launchd.Bootout(c.Context(), label); err != nil {
				return err
			}
			infof(w, "unloaded %s", label)
			if keepPlist {
				return nil
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			infof(w, "removed %s", path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&keepPlist, "keep-plist", false, "unload but leave the plist on disk")
	return cmd
}

func newLaunchdListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List devtools-managed LaunchAgents",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			states, err := launchd.List(c.Context())
			if err != nil {
				return err
			}
			if len(states) == 0 {
				infof(c.OutOrStdout(), "no devtools-managed agents installed")
				return nil
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "LABEL\tLOADED\tPID\tLAST EXIT\tPLIST")
			for _, s := range states {
				pid, exit := "-", "-"
				if s.PID > 0 {
					pid = fmt.Sprint(s.PID)
				}
				if s.LastExit >= 0 {
					exit = fmt.Sprint(s.LastExit)
				}
				fmt.Fprintf(tw, "%s\t%t\t%s\t%s\t%s\n", s.Label, s.Loaded, pid, exit, s.Plist)
			}
			return tw.Flush()
		},
	}
}

func newLaunchdStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <name>",
		Short: "Show launchctl print output for an agent",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			out, err := launchd.Print(c.Context(), launchd.QualifyLabel(args[0]))
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), out)
			return nil
		},
	}
}

func newLaunchdRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "run <name>",
		Aliases: []string{"kickstart", "start"},
		Short:   "Run a loaded agent now",
		Args:    cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			label := launchd.QualifyLabel(args[0])
			if g.dryRun {
				infof(c.OutOrStdout(), "dry-run: would kickstart %s", label)
				return nil
			}
			if err := launchd.Kickstart(c.Context(), label); err != nil {
				return err
			}
			infof(c.OutOrStdout(), "kickstarted %s", label)
			return nil
		},
	}
}

func newLaunchdLogsCmd() *cobra.Command {
	var lines int
	var errLog bool
	cmd := &cobra.Command{
		Use:   "logs <name>",
		Short: "Print the tail of an agent's log",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			dir, err := launchd.LogDir()
			if err != nil {
				return err
			}
			suffix := ".out.log"
			if errLog {
				suffix = ".err.log"
			}
			path := dir + "/" + launchd.QualifyLabel(args[0]) + suffix
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
			if lines > 0 && len(all) > lines {
				all = all[len(all)-lines:]
			}
			fmt.Fprintln(c.OutOrStdout(), strings.Join(all, "\n"))
			return nil
		},
	}
	cmd.Flags().IntVarP(&lines, "lines", "l", 50, "number of trailing lines to show (0 for all)")
	cmd.Flags().BoolVar(&errLog, "stderr", false, "show the stderr log instead of stdout")
	return cmd
}

func newLaunchdCatCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cat <name>",
		Short: "Print an agent's plist",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			path, err := launchd.PlistPath(launchd.QualifyLabel(args[0]))
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fmt.Fprint(c.OutOrStdout(), string(data))
			return nil
		},
	}
}

// parseEnv turns KEY=VALUE flags into a map.
func parseEnv(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--env %q is not KEY=VALUE", p)
		}
		out[k] = v
	}
	return out, nil
}
