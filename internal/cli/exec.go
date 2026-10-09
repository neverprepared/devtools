package cli

import (
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// runInteractive hands the terminal to another program (editors, pagers).
func runInteractive(c *cobra.Command, name string, args ...string) error {
	cmd := exec.CommandContext(c.Context(), name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
