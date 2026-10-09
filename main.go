// Command devtools is a personal developer toolbox: a single binary with many
// subcommands for day-to-day macOS dev chores (Teams presence, launchd agents,
// cron entries, and whatever comes next).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/neverprepared/devtools/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.NewRootCmd().ExecuteContext(ctx); err != nil {
		// A diagnostic command that ran fine but found a problem carries its
		// own exit code and has already printed its report.
		var exit *cli.ExitError
		if errors.As(err, &exit) {
			if exit.Err != nil {
				fmt.Fprintln(os.Stderr, "devtools:", exit.Err)
			}
			os.Exit(exit.Code)
		}
		// Cobra already printed usage errors; keep this terse.
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "devtools:", err)
		}
		os.Exit(1)
	}
}
