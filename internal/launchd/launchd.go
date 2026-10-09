// Package launchd creates and manages per-user LaunchAgents: the macOS way to
// run something on an interval or on a calendar schedule.
package launchd

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/neverprepared/devtools/internal/osx"
)

// LabelPrefix namespaces every agent devtools creates so `devtools launchd
// list` can tell ours apart from everything else in ~/Library/LaunchAgents.
const LabelPrefix = "com.devtools."

// Agent is the subset of a LaunchAgent that devtools manages.
type Agent struct {
	Label            string
	Program          []string // ProgramArguments
	WorkingDirectory string
	Env              map[string]string
	StartInterval    time.Duration
	Calendar         []CalendarEntry
	RunAtLoad        bool
	KeepAlive        bool
	StdoutPath       string
	StderrPath       string
	Nice             *int
}

// QualifyLabel adds the devtools namespace to a bare name.
func QualifyLabel(name string) string {
	name = strings.TrimSpace(name)
	if strings.Contains(name, ".") && !strings.HasPrefix(name, LabelPrefix) {
		return name // caller supplied a fully-qualified label of their own
	}
	if strings.HasPrefix(name, LabelPrefix) {
		return name
	}
	return LabelPrefix + name
}

// AgentsDir is ~/Library/LaunchAgents. It is also the write-side platform
// gate: off macOS there is no such directory worth creating, so Write fails
// here rather than leaving a plist nothing will ever load.
func AgentsDir() (string, error) {
	if !osx.Supported() {
		return "", &osx.ErrUnsupported{What: "LaunchAgents"}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}

// LogDir is where devtools-managed agents write their output.
func LogDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Logs", "devtools"), nil
}

// PlistPath returns the on-disk path for a label.
func PlistPath(label string) (string, error) {
	dir, err := AgentsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, label+".plist"), nil
}

// Validate checks an agent is actually runnable before we write it out.
func (a *Agent) Validate() error {
	if strings.TrimSpace(a.Label) == "" {
		return fmt.Errorf("label is required")
	}
	if len(a.Program) == 0 {
		return fmt.Errorf("no command given (put it after --)")
	}
	if a.StartInterval == 0 && len(a.Calendar) == 0 && !a.RunAtLoad && !a.KeepAlive {
		return fmt.Errorf("agent would never run: pass --interval, --at, --run-at-load, or --keep-alive")
	}
	if a.StartInterval != 0 && len(a.Calendar) > 0 {
		return fmt.Errorf("--interval and --at are mutually exclusive")
	}
	if a.StartInterval != 0 && a.StartInterval < time.Second {
		return fmt.Errorf("--interval must be at least 1s")
	}
	// launchd execs the program directly: no PATH lookup, no shell.
	prog := a.Program[0]
	if !strings.Contains(prog, "/") {
		resolved, err := exec.LookPath(prog)
		if err != nil {
			return fmt.Errorf("launchd needs an absolute program path and %q is not on PATH: %w", prog, err)
		}
		a.Program[0] = resolved
	} else if abs, err := filepath.Abs(prog); err == nil {
		a.Program[0] = abs
	}
	if fi, err := os.Stat(a.Program[0]); err != nil {
		return fmt.Errorf("program %s: %w", a.Program[0], err)
	} else if fi.IsDir() {
		return fmt.Errorf("program %s is a directory", a.Program[0])
	}
	return nil
}

// ApplyDefaultLogs fills in per-label log paths when none were given.
func (a *Agent) ApplyDefaultLogs() error {
	dir, err := LogDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if a.StdoutPath == "" {
		a.StdoutPath = filepath.Join(dir, a.Label+".out.log")
	}
	if a.StderrPath == "" {
		a.StderrPath = filepath.Join(dir, a.Label+".err.log")
	}
	return nil
}

// Plist renders the agent as a launchd property list.
func (a *Agent) Plist() string {
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")

	key := func(k string) { fmt.Fprintf(&b, "\t<key>%s</key>\n", esc(k)) }
	str := func(k, v string) { key(k); fmt.Fprintf(&b, "\t<string>%s</string>\n", esc(v)) }
	integer := func(k string, v int) { key(k); fmt.Fprintf(&b, "\t<integer>%d</integer>\n", v) }
	boolean := func(k string, v bool) {
		key(k)
		if v {
			b.WriteString("\t<true/>\n")
		} else {
			b.WriteString("\t<false/>\n")
		}
	}

	str("Label", a.Label)

	key("ProgramArguments")
	b.WriteString("\t<array>\n")
	for _, arg := range a.Program {
		fmt.Fprintf(&b, "\t\t<string>%s</string>\n", esc(arg))
	}
	b.WriteString("\t</array>\n")

	if a.WorkingDirectory != "" {
		str("WorkingDirectory", a.WorkingDirectory)
	}
	if len(a.Env) > 0 {
		key("EnvironmentVariables")
		b.WriteString("\t<dict>\n")
		for _, k := range sortedKeys(a.Env) {
			fmt.Fprintf(&b, "\t\t<key>%s</key>\n\t\t<string>%s</string>\n", esc(k), esc(a.Env[k]))
		}
		b.WriteString("\t</dict>\n")
	}
	if a.StartInterval > 0 {
		integer("StartInterval", int(a.StartInterval.Seconds()))
	}
	if len(a.Calendar) > 0 {
		key("StartCalendarInterval")
		b.WriteString("\t<array>\n")
		for _, e := range a.Calendar {
			b.WriteString("\t\t<dict>\n")
			for _, f := range []struct {
				name string
				val  *int
			}{
				{"Minute", e.Minute}, {"Hour", e.Hour},
				{"Day", e.Day}, {"Weekday", e.Weekday}, {"Month", e.Month},
			} {
				if f.val != nil {
					fmt.Fprintf(&b, "\t\t\t<key>%s</key>\n\t\t\t<integer>%d</integer>\n", f.name, *f.val)
				}
			}
			b.WriteString("\t\t</dict>\n")
		}
		b.WriteString("\t</array>\n")
	}
	boolean("RunAtLoad", a.RunAtLoad)
	if a.KeepAlive {
		boolean("KeepAlive", true)
	}
	if a.Nice != nil {
		integer("Nice", *a.Nice)
	}
	if a.StdoutPath != "" {
		str("StandardOutPath", a.StdoutPath)
	}
	if a.StderrPath != "" {
		str("StandardErrorPath", a.StderrPath)
	}
	// ProcessType Background keeps these out of the foreground QoS tier.
	str("ProcessType", "Background")

	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func esc(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Write saves the plist to ~/Library/LaunchAgents and returns the path.
func (a *Agent) Write() (string, error) {
	path, err := PlistPath(a.Label)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(a.Plist()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// --- launchctl plumbing ---

func domain() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return "gui/" + u.Uid, nil
}

func launchctl(ctx context.Context, args ...string) (string, error) {
	if !osx.Supported() {
		return "", &osx.ErrUnsupported{What: "launchctl"}
	}
	cmd := exec.CommandContext(ctx, "launchctl", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("launchctl %s: %w: %s", strings.Join(args, " "), err, text)
	}
	return text, nil
}

// Bootstrap loads a plist into the user's GUI domain, replacing any previous
// copy so repeated installs are idempotent.
func Bootstrap(ctx context.Context, label, path string) error {
	dom, err := domain()
	if err != nil {
		return err
	}
	// Ignore the bootout error: a not-yet-loaded agent is the common case.
	_, _ = launchctl(ctx, "bootout", dom+"/"+label)
	if _, err := launchctl(ctx, "bootstrap", dom, path); err != nil {
		// Older macOS, or a domain that refuses bootstrap: fall back to load -w.
		if _, lerr := launchctl(ctx, "load", "-w", path); lerr != nil {
			return err
		}
	}
	return nil
}

// Bootout unloads an agent. A not-loaded agent is not an error.
func Bootout(ctx context.Context, label string) error {
	dom, err := domain()
	if err != nil {
		return err
	}
	out, err := launchctl(ctx, "bootout", dom+"/"+label)
	if err != nil && !strings.Contains(out, "No such process") && !strings.Contains(out, "Could not find") {
		return err
	}
	return nil
}

// Kickstart runs an agent right now (-k restarts it if already running).
func Kickstart(ctx context.Context, label string) error {
	dom, err := domain()
	if err != nil {
		return err
	}
	_, err = launchctl(ctx, "kickstart", "-k", dom+"/"+label)
	return err
}

// Print returns `launchctl print` output for an agent.
func Print(ctx context.Context, label string) (string, error) {
	dom, err := domain()
	if err != nil {
		return "", err
	}
	return launchctl(ctx, "print", dom+"/"+label)
}

// State is the runtime status of one managed agent.
type State struct {
	Label    string
	Plist    string
	Loaded   bool
	PID      int
	LastExit int
}

// List reports every devtools-managed agent on disk plus its load state.
func List(ctx context.Context) ([]State, error) {
	dir, err := AgentsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	loaded, _ := loadedAgents(ctx)

	var out []State
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, LabelPrefix) || !strings.HasSuffix(name, ".plist") {
			continue
		}
		label := strings.TrimSuffix(name, ".plist")
		st := State{Label: label, Plist: filepath.Join(dir, name), LastExit: -1}
		if l, ok := loaded[label]; ok {
			st.Loaded, st.PID, st.LastExit = true, l.PID, l.LastExit
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

type loadedAgent struct {
	PID      int
	LastExit int
}

// loadedAgents parses `launchctl list`, whose columns are PID, last exit, label.
func loadedAgents(ctx context.Context) (map[string]loadedAgent, error) {
	out, err := launchctl(ctx, "list")
	if err != nil {
		return nil, err
	}
	res := map[string]loadedAgent{}
	for i, line := range strings.Split(out, "\n") {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		la := loadedAgent{PID: -1, LastExit: -1}
		if n, err := strconv.Atoi(fields[0]); err == nil {
			la.PID = n
		}
		if n, err := strconv.Atoi(fields[1]); err == nil {
			la.LastExit = n
		}
		res[fields[2]] = la
	}
	return res, nil
}
