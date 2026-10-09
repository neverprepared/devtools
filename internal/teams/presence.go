// Package teams drives the Microsoft Teams desktop client through its command
// box (Cmd+E) via AppleScript, since Teams exposes no local API for presence.
package teams

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/neverprepared/devtools/internal/osx"
)

// DefaultApp is the application name of the current Teams client. Teams
// Classic registers as "Microsoft Teams classic".
const DefaultApp = "Microsoft Teams"

// Status is one presence state reachable from the Teams command box.
type Status struct {
	Name    string   // canonical name, used as the subcommand
	Command string   // slash command typed into the command box
	Summary string   // one-line help text
	Aliases []string // alternate spellings accepted by Resolve
}

// Statuses are the presence states devtools knows how to set.
var Statuses = []Status{
	{Name: "available", Command: "/available", Summary: "Set presence to Available (green)", Aliases: []string{"active", "online", "green", "free"}},
	{Name: "away", Command: "/away", Summary: "Set presence to Away (yellow)", Aliases: []string{"idle", "yellow"}},
	{Name: "busy", Command: "/busy", Summary: "Set presence to Busy (red)", Aliases: []string{"red"}},
	{Name: "dnd", Command: "/dnd", Summary: "Set presence to Do not disturb", Aliases: []string{"donotdisturb", "do-not-disturb", "focus"}},
	{Name: "brb", Command: "/brb", Summary: "Set presence to Be right back", Aliases: []string{"berightback", "be-right-back"}},
	{Name: "offline", Command: "/offline", Summary: "Appear offline", Aliases: []string{"appearoffline", "invisible"}},
}

// Resolve maps a user-supplied name or alias to a Status.
func Resolve(name string) (Status, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	want = strings.TrimPrefix(want, "/")
	for _, s := range Statuses {
		if s.Name == want {
			return s, nil
		}
		for _, a := range s.Aliases {
			if a == want {
				return s, nil
			}
		}
	}
	return Status{}, fmt.Errorf("unknown status %q (known: %s)", name, strings.Join(StatusNames(), ", "))
}

// StatusNames returns the canonical status names, sorted.
func StatusNames() []string {
	names := make([]string, 0, len(Statuses))
	for _, s := range Statuses {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// Options tunes how the command box is driven. The delays exist because
// AppleScript keystrokes race the Electron UI; the defaults match what works
// reliably on a warm app, and slower machines may need --activate-delay bumped.
type Options struct {
	App           string
	ActivateDelay time.Duration
	KeyDelay      time.Duration
	Restore       bool // return focus to whatever app was frontmost
}

// DefaultOptions returns the tuned defaults.
func DefaultOptions() Options {
	return Options{
		App:           DefaultApp,
		ActivateDelay: 500 * time.Millisecond,
		KeyDelay:      200 * time.Millisecond,
		Restore:       true,
	}
}

func (o Options) app() string {
	if strings.TrimSpace(o.App) == "" {
		return DefaultApp
	}
	return o.App
}

// secs renders a duration the way AppleScript's `delay` wants it.
func secs(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", d.Seconds()), "0"), ".")
	if s == "" {
		return "0"
	}
	return s
}

// Script renders the AppleScript that sets the given status. restoreApp, when
// non-empty, is re-activated at the end so presence changes do not steal focus.
func Script(st Status, opts Options, restoreApp string) string {
	var b strings.Builder
	app := osx.Quote(opts.app())
	fmt.Fprintf(&b, "tell application %s to activate\n", app)
	fmt.Fprintf(&b, "delay %s\n", secs(opts.ActivateDelay))
	b.WriteString("tell application \"System Events\"\n")
	b.WriteString("\t-- open the Teams command box (Cmd+E)\n")
	b.WriteString("\tkeystroke \"e\" using {command down}\n")
	fmt.Fprintf(&b, "\tdelay %s\n", secs(opts.KeyDelay))
	fmt.Fprintf(&b, "\tkeystroke %s\n", osx.Quote(st.Command))
	fmt.Fprintf(&b, "\tdelay %s\n", secs(opts.KeyDelay))
	b.WriteString("\tkey code 36 -- Return\n")
	b.WriteString("end tell\n")
	if restoreApp != "" && restoreApp != opts.app() {
		fmt.Fprintf(&b, "delay %s\n", secs(opts.KeyDelay))
		// Restoring focus is a nicety: never let it fail a presence change.
		b.WriteString("try\n")
		fmt.Fprintf(&b, "\ttell application %s to activate\n", osx.Quote(restoreApp))
		b.WriteString("end try\n")
	}
	return b.String()
}

// Set drives Teams to the requested presence status.
func Set(ctx context.Context, st Status, opts Options) error {
	if !osx.Supported() {
		return &osx.ErrUnsupported{What: "teams presence"}
	}
	var restore string
	if opts.Restore {
		// Best effort: if we cannot read the frontmost app we simply do not
		// restore focus rather than failing the presence change.
		if front, err := osx.FrontmostApp(ctx); err == nil {
			restore = front
		}
	}
	if _, err := osx.Run(ctx, Script(st, opts, restore)); err != nil {
		return fmt.Errorf("set presence to %s: %w", st.Name, err)
	}
	return nil
}
