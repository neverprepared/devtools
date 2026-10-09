package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/neverprepared/devtools/internal/launchd"
	"github.com/neverprepared/devtools/internal/osx"
	"github.com/neverprepared/devtools/internal/teams"
)

type checkResult struct {
	Name   string
	OK     bool
	Detail string
	Fix    string
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the prerequisites devtools depends on",
		Long:  "Verify the local prerequisites: macOS, osascript, Accessibility permission, the Teams client, and launchctl.",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			results := []checkResult{platformCheck()}
			if osx.Supported() {
				results = append(results,
					binaryCheck("osascript"),
					binaryCheck("launchctl"),
					binaryCheck("crontab"),
					accessibilityCheck(ctx),
					teamsCheck(ctx),
					agentsDirCheck(),
				)
			}

			w := c.OutOrStdout()
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			failed := 0
			for _, r := range results {
				mark := "ok"
				if !r.OK {
					mark = "FAIL"
					failed++
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", mark, r.Name, r.Detail)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if failed == 0 {
				infof(w, "\nall %d checks passed", len(results))
				return nil
			}
			fmt.Fprintln(w)
			for _, r := range results {
				if !r.OK && r.Fix != "" {
					infof(w, "fix %s: %s", r.Name, r.Fix)
				}
			}
			return fmt.Errorf("%d of %d checks failed", failed, len(results))
		},
	}
}

func platformCheck() checkResult {
	return checkResult{
		Name:   "platform",
		OK:     osx.Supported(),
		Detail: runtime.GOOS + "/" + runtime.GOARCH,
		Fix:    "the teams and launchd commands are macOS-only",
	}
}

func binaryCheck(name string) checkResult {
	path, err := exec.LookPath(name)
	if err != nil {
		return checkResult{Name: name, Detail: "not found on PATH", Fix: "expected at /usr/bin/" + name}
	}
	return checkResult{Name: name, OK: true, Detail: path}
}

func accessibilityCheck(ctx context.Context) checkResult {
	ok, err := osx.HasAccessibility(ctx)
	detail := "terminal may send keystrokes via System Events"
	if err != nil {
		detail = "could not determine: " + err.Error()
	} else if !ok {
		detail = "System Events keystrokes are blocked"
	}
	return checkResult{
		Name:   "accessibility",
		OK:     err == nil && ok,
		Detail: detail,
		Fix:    "System Settings > Privacy & Security > Accessibility, then enable your terminal app",
	}
}

func teamsCheck(ctx context.Context) checkResult {
	if !osx.AppInstalled(ctx, teams.DefaultApp) {
		return checkResult{
			Name:   "microsoft teams",
			Detail: teams.DefaultApp + " not found",
			Fix:    "install Teams, or pass --app with the right application name",
		}
	}
	running, _ := osx.AppRunning(ctx, teams.DefaultApp)
	detail := "installed, running"
	if !running {
		detail = "installed, not running (devtools will launch it)"
	}
	return checkResult{Name: "microsoft teams", OK: true, Detail: detail}
}

func agentsDirCheck() checkResult {
	dir, err := launchd.AgentsDir()
	if err != nil {
		return checkResult{Name: "launchagents dir", Detail: err.Error()}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return checkResult{Name: "launchagents dir", Detail: err.Error(), Fix: "create " + dir + " by hand"}
	}
	return checkResult{Name: "launchagents dir", OK: true, Detail: dir}
}
