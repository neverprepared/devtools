// Package cli wires the devtools subcommand tree.
package cli

import (
	"fmt"
	"io"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is overridden at build time:
//
//	go build -ldflags "-X github.com/neverprepared/devtools/internal/cli.version=1.2.3"
var version = "dev"

// buildVersion reports the version to print. The ldflags stamp wins, since
// that is what the Makefile and GoReleaser set. Failing that, fall back to the
// module version the go tool embeds: `go install ...@v0.1.0` cannot pass
// ldflags, so without this that install path reports a useless "dev".
func buildVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	// "(devel)" is what a local `go build` with no module version reports.
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	return version
}

// globals holds the flags shared by every subcommand.
type globals struct {
	dryRun bool
	json   bool
	strict bool
}

// ExitError carries a specific process exit code out through cobra. Diagnostic
// commands use it so a failed check is distinguishable from a usage error.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

func (e *ExitError) Unwrap() error { return e.Err }

var g globals

// NewRootCmd builds the full command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "devtools",
		Short: "Personal developer toolbox for macOS",
		Long: `devtools is a single binary of small, sharp dev chores.

  devtools web check <url>              diagnose DNS, TCP, TLS and HTTP in order
  devtools ca export                    export TLS-inspection CAs as a PEM bundle
  devtools teams away                   set Microsoft Teams presence
  devtools launchd install ...          manage per-user LaunchAgents
  devtools cron add ...                 manage devtools-owned crontab entries
  devtools doctor                       check the local prerequisites

Every mutating command honours --dry-run, which prints what would happen
(including the generated AppleScript, plist, or crontab) and changes nothing.
Every diagnostic command honours --json and sets a meaningful exit code, so it
drops straight into a launchd agent or a cron entry.`,
		SilenceUsage:      true,
		SilenceErrors:     true,
		CompletionOptions: cobra.CompletionOptions{DisableDescriptions: false},
	}

	root.PersistentFlags().BoolVarP(&g.dryRun, "dry-run", "n", false, "print what would be done without doing it")
	root.PersistentFlags().BoolVar(&g.json, "json", false, "emit machine-readable JSON instead of text")
	root.PersistentFlags().BoolVar(&g.strict, "strict", false, "treat warnings as failures (exit 3)")

	root.AddCommand(
		newWebCmd(),
		newCACmd(),
		newTeamsCmd(),
		newLaunchdCmd(),
		newCronCmd(),
		newDoctorCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the devtools version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), buildVersion())
			return err
		},
	}
}

// infof writes a status line to the command's stdout.
func infof(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format+"\n", args...)
}
