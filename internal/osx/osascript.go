// Package osx wraps the small bits of macOS automation devtools needs:
// running AppleScript via osascript and asking about running applications.
//
// It is also where the platform gate lives. Supported and ErrUnsupported are
// the project's single vocabulary for "this needs macOS", used by the keychain
// and launchd packages too so every off-platform failure reads the same way.
package osx

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// ErrUnsupported is returned when an osx helper is called off macOS.
type ErrUnsupported struct{ What string }

func (e *ErrUnsupported) Error() string {
	return fmt.Sprintf("%s requires macOS (running on %s)", e.What, runtime.GOOS)
}

// Supported reports whether the host can run AppleScript.
func Supported() bool { return runtime.GOOS == "darwin" }

// Run executes an AppleScript source string with osascript and returns its
// trimmed stdout. stderr is folded into the error so permission problems
// ("not allowed assistive access") surface to the caller.
func Run(ctx context.Context, script string) (string, error) {
	if !Supported() {
		return "", &ErrUnsupported{What: "osascript"}
	}
	cmd := exec.CommandContext(ctx, "osascript", "-")
	cmd.Stdin = strings.NewReader(script)

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			return "", fmt.Errorf("osascript: %w", err)
		}
		return "", fmt.Errorf("osascript: %w: %s", err, msg)
	}
	return strings.TrimSpace(out.String()), nil
}

// Quote renders s as an AppleScript double-quoted string literal.
func Quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(s) + `"`
}

// FrontmostApp returns the name of the application currently in front.
func FrontmostApp(ctx context.Context) (string, error) {
	return Run(ctx, `tell application "System Events" to get name of first application process whose frontmost is true`)
}

// AppRunning reports whether an application with the given name is running.
func AppRunning(ctx context.Context, name string) (bool, error) {
	script := fmt.Sprintf(`tell application "System Events" to return (exists (application process %s))`, Quote(name))
	out, err := Run(ctx, script)
	if err != nil {
		return false, err
	}
	return out == "true", nil
}

// AppInstalled reports whether an application bundle with the given name can
// be resolved by Launch Services.
func AppInstalled(ctx context.Context, name string) bool {
	script := fmt.Sprintf(`tell application "Finder" to return POSIX path of (application file id (id of application %s) as alias)`, Quote(name))
	if _, err := Run(ctx, script); err == nil {
		return true
	}
	// Fall back to the obvious locations; the Finder route needs automation
	// permission that a fresh install may not have granted yet.
	script = fmt.Sprintf(`tell application "System Events" to return (exists disk item ("/Applications/" & %s & ".app"))`, Quote(name))
	out, err := Run(ctx, script)
	return err == nil && out == "true"
}

// HasAccessibility reports whether this process' parent (the terminal) has been
// granted Accessibility rights, which System Events keystrokes require.
func HasAccessibility(ctx context.Context) (bool, error) {
	// Asking System Events for UI element info fails with -1719/-25211 when
	// assistive access is denied, and succeeds harmlessly when granted.
	_, err := Run(ctx, `tell application "System Events" to get the name of every window of application process "Finder"`)
	if err == nil {
		return true, nil
	}
	msg := err.Error()
	for _, deny := range []string{"assistive access", "-1719", "-25211", "not allowed"} {
		if strings.Contains(msg, deny) {
			return false, nil
		}
	}
	return false, err
}
